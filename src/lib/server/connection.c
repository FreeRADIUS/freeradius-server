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
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
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

struct fr_conn {
	uint64_t		id;			//!< Unique identifier for the connection.
	fr_connection_state_t	state;			//!< Current connection state.

	fr_connection_init_t	init;			//!< Callback for initialising a connection.
	fr_connection_open_t	open;			//!< Callback for 'open' notification.
	fr_connection_close_t	close;			//!< Callback to close a connection.
	fr_connection_failed_t	failed;			//!< Callback for 'failed' notification.

	int			fd;			//!< File descriptor.
	fr_event_list_t		*el;			//!< Event list for timers and I/O events.

	fr_event_timer_t const	*connection_timer;	//!< Timer to prevent connections going on indefinitely.
	fr_event_timer_t const	*reconnection_timer;	//!< Timer to delay retries.

	fr_time_delta_t		connection_timeout;	//!< How long to wait in the
							//!< #FR_CONNECTION_STATE_CONNECTING state.
	fr_time_delta_t		reconnection_delay;	//!< How long to wait in the
							//!< #FR_CONNECTION_STATE_FAILED state.

	char const		*log_prefix;		//!< Prefix to add to log messages.

	void			*uctx;			//!< User data.
};

#define STATE_TRANSITION(_new) \
do { \
	DEBUG4("Changed state %s -> %s", \
	       fr_table_str_by_value(fr_connection_states, conn->state, "<INVALID>"), \
	       fr_table_str_by_value(fr_connection_states, _new, "<INVALID>")); \
	conn->state = _new; \
} while (0)

static void connection_state_init(fr_connection_t *conn, fr_time_t now);
static void connection_state_failed(fr_connection_t *conn, fr_time_t now);

/** The requisite period of time has passed, try and re-open the connection
 *
 * @param[in] el	the time event ocurred on.
 * @param[in] now	the current time.
 * @param[in] uctx	The #fr_connection_t the fd is associated with.
 */
static void _reconnect_delay_done(UNUSED fr_event_list_t *el, fr_time_t now, void *uctx)
{
	fr_connection_t *conn = talloc_get_type_abort(uctx, fr_connection_t);

	connection_state_init(conn, now);
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
static void connection_state_failed(fr_connection_t *conn, fr_time_t now)
{
	fr_connection_state_t prev;
	rad_assert(conn->state != FR_CONNECTION_STATE_FAILED);

	if (conn->fd >= 0) fr_event_fd_delete(conn->el, conn->fd, FR_EVENT_FILTER_IO);	/* Don't leave lingering events */
	if (conn->close) conn->close(conn->fd, conn->uctx);
	conn->fd = -1;

	prev = conn->state;
	STATE_TRANSITION(FR_CONNECTION_STATE_FAILED);

	/*
	 *	If there's a failed callback, give it the
	 *	opportunity to suspend/destroy the
	 *	connection.
	 */
	if (conn->failed) {
		fr_connection_state_t ret;

		/*
		 *	Callback may free the connection, so we
		 *	set this before calling the callback, so
		 *	if the connection isn't freed it's in the
		 *	correct state, without us needing to check.
		 */
		conn->state = FR_CONNECTION_STATE_HALTED;
		ret = conn->failed(conn->fd, prev, conn->uctx);
		switch (ret) {
		case FR_CONNECTION_STATE_INIT:
			conn->state = prev;
			break;

		case FR_CONNECTION_STATE_HALTED:		/* Do nothing */
			DEBUG4("Changed state %s -> %s",
			       fr_table_str_by_value(fr_connection_states, prev, "<INVALID>"),
			       fr_table_str_by_value(fr_connection_states, FR_CONNECTION_STATE_HALTED, "<INVALID>"));
			return;

		default:
			rad_assert(0);
		}
	}

	switch (prev) {
	case FR_CONNECTION_STATE_INIT:				/* Failed during initialisation */
	case FR_CONNECTION_STATE_CONNECTED:			/* Failed after connecting */
	case FR_CONNECTION_STATE_CONNECTING:			/* Failed during connecting */
		STATE_TRANSITION(FR_CONNECTION_STATE_FAILED);
		fr_event_timer_at(conn, conn->el, &conn->reconnection_timer,
				  now + conn->reconnection_delay, _reconnect_delay_done, conn);
		break;

	case FR_CONNECTION_STATE_TIMEOUT:			/* Failed during connecting */
		connection_state_init(conn, now);
		break;

	default:
		rad_assert(0);
	}
}

/** Connection timeout
 *
 * Fd didn't become writable within the configured period of time.
 *
 * @param[in] el	the time event ocurred on.
 * @param[in] now	the current time.
 * @param[in] uctx	The #fr_connection_t the fd is associated with.
 */
static void _connection_timeout(UNUSED fr_event_list_t *el, fr_time_t now, void *uctx)
{
	fr_connection_t *conn = talloc_get_type_abort(uctx, fr_connection_t);

	ERROR("Connection failed - timed out after %pVs", fr_box_time_delta(conn->connection_timeout));
	STATE_TRANSITION(FR_CONNECTION_STATE_TIMEOUT);
	connection_state_failed(conn, now);
}

/** Receive an error notification when we're connecting a socket
 *
 * @param[in] el	event list the I/O event occurred on.
 * @param[in] sock	the I/O even occurred for.
 * @param[in] flags	from_kevent.
 * @param[in] fd_errno	from kevent.
 * @param[in] uctx	The #fr_connection_t this fd is associated with.
 */
static void _connection_error(UNUSED fr_event_list_t *el, UNUSED int sock, UNUSED int flags, int fd_errno, void *uctx)
{
	fr_connection_t *conn = talloc_get_type_abort(uctx, fr_connection_t);

	/*
	 *	Explicit error occurred, delete the connection timer
	 */
	fr_event_timer_delete(conn->el, &conn->connection_timer);

	ERROR("Connection failed: %s", fr_syserror(fd_errno));
	connection_state_failed(conn, fr_time());
}

/** Receive a write notification after connecting a socket
 *
 * @param[in] el	event list the I/O event occurred on.
 * @param[in] sock	the I/O even occurred for.
 * @param[in] flags	from kevent.
 * @param[in] uctx	The #fr_connection_t this fd is associated with.
 */
static void _connection_writable(UNUSED fr_event_list_t *el, UNUSED int sock, UNUSED int flags, void *uctx)
{
	fr_connection_t		*conn = talloc_get_type_abort(uctx, fr_connection_t);
	fr_connection_state_t	ret;

	rad_assert(conn->open);	/* I/O handler should not be called unless we have an open callback */

	/*
	 *	Connection is writable, delete the connection timer
	 */
	fr_event_timer_delete(conn->el, &conn->connection_timer);
	fr_event_fd_delete(conn->el, conn->fd, FR_EVENT_FILTER_IO);

	ret = conn->open(conn->el, conn->fd, conn->uctx);
	if (conn->state == FR_CONNECTION_STATE_FAILED) return;	/* async signal that connection failed */

	switch (ret) {
	case FR_CONNECTION_STATE_CONNECTED:
		DEBUG2("Connection established");
		STATE_TRANSITION(ret);
		return;

	/*
	 *	Open callback failed
	 */
	case FR_CONNECTION_STATE_FAILED:
		PERROR("Connection failed");
		connection_state_failed(conn, fr_time());
		return;

	default:
		rad_assert(0);
	}
}

/** Enter the initialising state
 *
 * @param[in] conn	being initialised.
 * @param[in] now	the current ime.
 */
static void connection_state_init(fr_connection_t *conn, fr_time_t now)
{
	fr_connection_state_t ret;

	rad_assert((conn->state == FR_CONNECTION_STATE_HALTED) || (conn->state == FR_CONNECTION_STATE_FAILED));

	DEBUG2("Connection initialising");

	STATE_TRANSITION(FR_CONNECTION_STATE_INIT);

	/*
	 *	If we have an init callback, call it.
	 */
	if (conn->init) {
		ret = conn->init(&conn->fd, conn->uctx);
		if (conn->state == FR_CONNECTION_STATE_FAILED) return;	/* async signal that connection failed */
	} else {
		ret = FR_CONNECTION_STATE_CONNECTING;
	}

	switch (ret) {
	case FR_CONNECTION_STATE_CONNECTING:
		DEBUG2("Connection initialised");
		STATE_TRANSITION(ret);

		/*
		 *	If an open callback is provided, install an I/O
		 *	handler to determine when the FD is writable
		 *	and therefore open.
		 */
		if (conn->open) {
			rad_assert(conn->fd >= 0);	/* ->init() must provide a valid fd */

			/*
			 *	If connection becomes writable we
			 *	assume it's open.
			 */
			if (fr_event_fd_insert(conn, conn->el, conn->fd,
					       NULL,
					       _connection_writable,
					       _connection_error,
					       conn) < 0) {
				PERROR("Failed inserting file descriptor (%i) into event loop %p",
				       conn->fd, conn->el);
				connection_state_failed(conn, now);
				return;
			}
		}

		/*
		 *	If there's a connection timeout,
		 *	set, then add the timer.
		 */
		if (conn->connection_timeout) {
			fr_event_timer_at(conn, conn->el, &conn->connection_timer,
				      	  now + conn->connection_timeout,
				      	  _connection_timeout, conn);
		}
		break;

	/*
	 *	Initialisation callback failed
	 */
	case FR_CONNECTION_STATE_FAILED:
		PERROR("Connection initialisation failed");
		connection_state_failed(conn, now);
		break;

	default:
		rad_assert(0);
	}
}

/** Get the event list associated with the connection
 *
 * @param[in] conn to retrieve fd from.
 * @return the event list associated with the connection.
 */
fr_event_list_t *fr_connection_get_el(fr_connection_t const *conn)
{
	return conn->el;
}

/** Get the file descriptor associated with a connection
 *
 * @param[in] conn to retrieve fd from.
 * @return
 *	- -1 if no valid file descriptor is available.
 *	- >= 0 - The file descriptor.
 */
int fr_connection_get_fd(fr_connection_t const *conn)
{
	return conn->fd;
}

/** Set the file descriptor associated with a connection
 *
 * @note Should only be used if no conn->open callback is provided, and the init
 *	 function is either NULL, or is unable to provide a file descriptor.
 *
 * @param[in] conn	to set fd for.
 * @param[in] fd	to set.  Must be >= 0.
 */
void fr_connection_set_fd(fr_connection_t *conn, int fd)
{
	rad_assert(fd >= 0);
	rad_assert(!conn->open);

	conn->fd = fd;
}

/** Close a connection if it's freed
 *
 * @param[in] conn to free.
 * @return 0
 */
static int _connection_free(fr_connection_t *conn)
{
	switch (conn->state) {
	case FR_CONNECTION_STATE_HALTED:
		break;

	default:
		if (conn->fd >= 0) {
			DEBUG2("Closing connection (%i)", conn->fd);
			fr_event_fd_delete(conn->el, conn->fd, FR_EVENT_FILTER_IO);
			conn->close(conn->fd, conn->uctx);
			conn->fd = -1;
		}
		break;
	}
	return 0;
}

/** Allocate a new connection
 *
 * After the connection has been allocated, it should be started with a call to #fr_connection_signal_init.
 *
 * The connection state machine can detect when the connection is open in one of two ways.
 * If an open callback is provided, then once the init phase is complete, the connection state machine
 * will install an I/O handler to determine when the fd is writable (and therefor open).
 *
 * If an open callback is not provided, then once the init phase is complete, the connection state
 * machine should be signalled by calling #fr_connection_signal_open.  This allows the connection state
 * machine to work with more difficult library APIs, which may not return control to the caller as
 * connections are opened.
 *
 * @note If the init callback does not provide the file descriptor, then the file descriptor must be provided
 * via #fr_connection_set_fd, and #fr_connection_signal_open called.
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
				     void *uctx)
{
	fr_connection_t *conn;

	rad_assert(el);

	conn = talloc_zero(ctx, fr_connection_t);
	if (!conn) return NULL;
	talloc_set_destructor(conn, _connection_free);

	conn->id = atomic_fetch_add_explicit(&connection_counter, 1, memory_order_relaxed);
	conn->state = FR_CONNECTION_STATE_HALTED;
	conn->el = el;
	conn->fd = -1;
	conn->reconnection_delay = reconnection_delay;
	conn->connection_timeout = connection_timeout;
	conn->init = init;
	conn->open = open;
	conn->close = close;
	conn->log_prefix = talloc_typed_strdup(conn, log_prefix);
	conn->uctx = uctx;

	return conn;
}

/** Set an (optional) callback to be called on connection timeout/failure
 *
 */
void fr_connection_failed_func(fr_connection_t *conn, fr_connection_failed_t func)
{
	conn->failed = func;
}

/** Asynchronously signal a halted connection to start
 *
 */
void fr_connection_signal_init(fr_connection_t *conn)
{
	switch (conn->state) {
	case FR_CONNECTION_STATE_HALTED:
		connection_state_init(conn, fr_time());
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
void fr_connection_signal_open(fr_connection_t *conn)
{
	rad_assert(!conn->open);	/* Use one or the other not both! */

	switch (conn->state) {
	case FR_CONNECTION_STATE_CONNECTING:
		DEBUG2("Connection established");
		STATE_TRANSITION(FR_CONNECTION_STATE_CONNECTED);
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
		connection_state_failed(conn, fr_time());
		return;
	}
}
