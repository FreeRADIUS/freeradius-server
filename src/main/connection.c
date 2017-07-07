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
 * @file connection.c
 * @brief Simple state machine for managing connection states.
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#define LOG_PREFIX "(%" PRIu64 ") %s - "
#define LOG_PREFIX_ARGS conn->id, conn->log_prefix

#ifdef HAVE_STDATOMIC_H
#  include <stdatomic.h>
#else
#  include <freeradius-devel/stdatomic.h>
#endif
#include <talloc.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/event.h>
#include <freeradius-devel/connection.h>
#include <freeradius-devel/libradius.h>
#include <freeradius-devel/radiusd.h>

FR_NAME_NUMBER const fr_connection_states[] = {
	{ "HALTED",		FR_CONNECTION_STATE_HALTED },
	{ "INIT",		FR_CONNECTION_STATE_INIT },
	{ "CONNECTING",		FR_CONNECTION_STATE_CONNECTING },
	{ "TIMEOUT",		FR_CONNECTION_STATE_TIMEOUT },
	{ "CONNECTED",		FR_CONNECTION_STATE_CONNECTED },
	{ "FAILED",		FR_CONNECTION_STATE_FAILED },

	{ NULL, 0 }
};

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

	struct timeval		connection_timeout;	//!< How long to wait in the
							//!< #FR_CONNECTION_STATE_CONNECTING state.
	struct timeval		reconnection_delay;	//!< How long to wait in the
							//!< #FR_CONNECTION_STATE_FAILED state.

	char const		*log_prefix;		//!< Prefix to add to log messages.

	void			*uctx;			//!< User data.
};

#define STATE_TRANSITION(_new) \
do { \
	DEBUG4("Changed state %s -> %s", \
	       fr_int2str(fr_connection_states, conn->state, "<INVALID>"), \
	       fr_int2str(fr_connection_states, _new, "<INVALID>")); \
	conn->state = _new; \
} while (0)

static void connection_state_init(fr_connection_t *conn, struct timeval *now);
static void connection_state_failed(fr_connection_t *conn, struct timeval *now);

/** The requisite period of time has passed, try and re-open the connection
 *
 * @param[in] el	the time event ocurred on.
 * @param[in] now	the current time.
 * @param[in] uctx	The #fr_connection_t the fd is associated with.
 */
static void _reconnect_delay_done(UNUSED fr_event_list_t *el, struct timeval *now, void *uctx)
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
static void connection_state_failed(fr_connection_t *conn, struct timeval *now)
{
	fr_connection_state_t prev;
	rad_assert(conn->state != FR_CONNECTION_STATE_FAILED);

	fr_event_fd_delete(conn->el, conn->fd);			/* Don't leave lingering events */
	conn->close(conn->fd, conn->uctx);
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
			connection_state_init(conn, now);
			break;

		case FR_CONNECTION_STATE_HALTED:	/* Do nothing */
			STATE_TRANSITION(FR_CONNECTION_STATE_HALTED);
			return;

		default:
			rad_assert(0);
		}
	}

	switch (prev) {
	case FR_CONNECTION_STATE_INIT:				/* Failed during initialisation */
	case FR_CONNECTION_STATE_CONNECTED:			/* Failed after connecting */
	case FR_CONNECTION_STATE_CONNECTING:			/* Failed during connecting */
	{
		struct timeval when;

		fr_timeval_add(&when, now, &conn->reconnection_delay);
		fr_event_timer_insert(conn, conn->el, &conn->reconnection_timer,
				      &when, _reconnect_delay_done, conn);
	}
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
static void _connection_timeout(UNUSED fr_event_list_t *el, struct timeval *now, void *uctx)
{
	fr_connection_t *conn = talloc_get_type_abort(uctx, fr_connection_t);

	ERROR("Connection failed - timed out after %pVs", fr_box_timeval(conn->connection_timeout));
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
	struct timeval	now;

	/*
	 *	Explicit error occurred, delete the connection timer
	 */
	fr_event_timer_delete(conn->el, &conn->connection_timer);

	ERROR("Connection failed: %s", fr_syserror(fd_errno));
	gettimeofday(&now, NULL);
	connection_state_failed(conn, &now);
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
	fr_connection_t *conn = talloc_get_type_abort(uctx, fr_connection_t);
	fr_connection_state_t ret;

	/*
	 *	Connection is writable, delete the connection timer
	 */
	fr_event_timer_delete(conn->el, &conn->connection_timer);
	fr_event_fd_delete(conn->el, conn->fd);

	ret = conn->open(conn->fd, conn->el, conn->uctx);
	switch (ret) {
	case FR_CONNECTION_STATE_CONNECTED:
		DEBUG2("Connection established");
		STATE_TRANSITION(ret);
		return;

	/*
	 *	Open callback failed
	 */
	case FR_CONNECTION_STATE_FAILED:
	{
		struct timeval now;

		PERROR("Connection failed");
		gettimeofday(&now, NULL);
		connection_state_failed(conn, &now);
		return;
	}

	default:
		rad_assert(0);
	}
}

/** Enter the initialising state
 *
 * @param[in] conn	being initialised.
 * @param[in] now	the current ime.
 */
static void connection_state_init(fr_connection_t *conn, struct timeval *now)
{
	fr_connection_state_t ret;
	int fd = -1;

	rad_assert((conn->state == FR_CONNECTION_STATE_HALTED) || (conn->state == FR_CONNECTION_STATE_FAILED));

	DEBUG2("Connection initialising");
	STATE_TRANSITION(FR_CONNECTION_STATE_INIT);

	ret = conn->init(&fd, conn->uctx);
	switch (ret) {
	case FR_CONNECTION_STATE_CONNECTING:
	{
		struct timeval when = { 0, 0 };

		DEBUG2("Connection initialised");
		STATE_TRANSITION(ret);
		fr_timeval_add(&when, now, &conn->connection_timeout);

		/*
		 *	If connection becomes writable we
		 *	assume it's open.
		 */
		if (fr_event_fd_insert(conn, conn->el, fd, NULL, _connection_writable, _connection_error, conn) < 0) {
			PERROR("Failed inserting file descriptor (%i) into event loop %p", fd, conn->el);
			connection_state_failed(conn, now);
			return;
		}
		fr_event_timer_insert(conn, conn->el, &conn->connection_timer,
				      &when, _connection_timeout, conn);
		conn->fd = fd;
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
			fr_event_fd_delete(conn->el, conn->fd);
			conn->close(conn->fd, conn->uctx);
			conn->fd = -1;
		}
		break;
	}
	return 0;
}

/** Allocate a new connection
 *
 * After the connection has been allocated, the state machine will attempt to open the connection
 * immediately, but as the state machine is non-blocking the connection may not be open when
 * when return.
 *
 * In all cases the open callback should be used to install I/O handlers once the connection is open.
 *
 * @param[in] ctx		to allocate connection handle in.  If the connection
 *				handle is freed, and the #fr_connection_state_t is
 *				#FR_CONNECTION_STATE_CONNECTING or #FR_CONNECTION_STATE_CONNECTED the
 *				close callback will be called.
 * @param[in] el		to use for timer events, and to pass to the #fr_connection_open_t callback.
 * @param[in] connection_timeout	How long to wait for a connection to open.
 * @param[in] reconnection_delay	How long to wait on connection failure.
 * @param[in] init		Callback to initialise a new file descriptor.
 * @param[in] open		Callback to receive notifications that the connection is open.
 * @param[in] close		Callback to close the connection.
 * @param[in] log_prefix	To prepend to log messages.
 * @param[in] uctx		User context to pass to callbacks.
 * @return
 *	- A new #fr_connection_t on success.
 *	- NULL on failure.
 */
fr_connection_t *fr_connection_alloc(TALLOC_CTX *ctx, fr_event_list_t *el,
				     struct timeval *connection_timeout, struct timeval *reconnection_delay,
				     fr_connection_init_t init, fr_connection_open_t open, fr_connection_close_t close,
				     char const *log_prefix,
				     void *uctx)
{
	fr_connection_t *conn;

	rad_assert(el);
	rad_assert(init && open && close);

	conn = talloc_zero(ctx, fr_connection_t);
	if (!conn) return NULL;
	talloc_set_destructor(conn, _connection_free);

	conn->id = atomic_fetch_add_explicit(&connection_counter, 1, memory_order_relaxed);
	conn->state = FR_CONNECTION_STATE_HALTED;
	conn->el = el;
	conn->reconnection_delay = *reconnection_delay;
	conn->connection_timeout = *connection_timeout;
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

/** Start a new or halted connection
 *
 */
void fr_connection_start(fr_connection_t *conn)
{
	struct timeval now;

	gettimeofday(&now, NULL);

	switch (conn->state) {
	case FR_CONNECTION_STATE_HALTED:
		connection_state_init(conn, &now);
		break;

	default:
		rad_assert(0);
	}
}

/** Asynchronously signal the connection should be reconnected
 *
 * Should be called if the caller has knowledge that the connection is bad
 * and should be reconnected.
 *
 * @param[in] conn		to reconnect.
 */
void fr_connection_reconnect(fr_connection_t *conn)
{
	switch (conn->state) {
	case FR_CONNECTION_STATE_FAILED:	/* Don't circumvent reconnection_delay */
	case FR_CONNECTION_STATE_INIT:		/* Already initialising */
		break;

	case FR_CONNECTION_STATE_HALTED:
		fr_connection_start(conn);
		return;

	case FR_CONNECTION_STATE_CONNECTING:
	case FR_CONNECTION_STATE_CONNECTED:
	case FR_CONNECTION_STATE_TIMEOUT:
	{
		struct timeval now;

		gettimeofday(&now, NULL);

		DEBUG2("Reconnecting...");

		connection_state_failed(conn, &now);
	}
		return;
	}
}
