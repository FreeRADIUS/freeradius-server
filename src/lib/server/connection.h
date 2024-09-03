#pragma once
/*
 *   This program is free software; you can redistribute it and/or modify
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
 * @file lib/server/connection.h
 * @brief Simple state machine for managing connection states.
 *
 * @copyright 2017-2020 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(connection_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/util/event.h>
#include <freeradius-devel/util/table.h>
#include <freeradius-devel/util/talloc.h>

#ifdef _CONST
#  error _CONST can only be defined in the local header
#endif
#ifndef _CONNECTION_PRIVATE
typedef struct connection_pub_s connection_t; /* We use the private version of the connection_t */
#  define _CONST const
#else
#  define _CONST
#endif

typedef enum {
	CONNECTION_STATE_HALTED = 0,		//!< The connection is in a halted stat.  It does not have
						///< a valid file descriptor, and it will not try and
						///< and create one.
	CONNECTION_STATE_INIT,			//!< Init state, sets up connection.
	CONNECTION_STATE_CONNECTING,		//!< Waiting for connection to establish.
	CONNECTION_STATE_TIMEOUT,		//!< Timeout during #CONNECTION_STATE_CONNECTING.
	CONNECTION_STATE_CONNECTED,		//!< File descriptor is open (ready for writing).
	CONNECTION_STATE_SHUTDOWN,		//!< Connection is shutting down.
	CONNECTION_STATE_FAILED,		//!< Connection has failed.
	CONNECTION_STATE_CLOSED,		//!< Connection has been closed.
	CONNECTION_STATE_MAX
} connection_state_t;

/** Public fields for the connection
 *
 * This saves the overhead of using accessors for commonly used fields in
 * connections.
 *
 * Though these fields are public, they should _NOT_ be modified by clients of
 * the connection API.
 */
struct connection_pub_s {
	char const		* _CONST name;		//!< Prefix to add to log messages.

	connection_state_t _CONST	state;		//!< Current connection state.
	connection_state_t _CONST	prev;		//!< The previous state the connection was in.
	uint64_t _CONST			id;		//!< Unique identifier for the connection.
	void			* _CONST h;		//!< Connection handle
	fr_event_list_t		* _CONST el;		//!< Event list for timers and I/O events.

	uint64_t _CONST			reconnected;	//!< How many times we've attempted to establish or
							///< re-establish this connection.
	uint64_t _CONST			timed_out;	//!< How many times has this connection timed out when
							///< connecting.
	bool _CONST			triggers;	//!< do we run the triggers?
};

typedef enum {
	CONNECTION_FAILED = 0,			//!< Connection is being reconnected because it failed.
	CONNECTION_EXPIRED 			//!< Connection is being reconnected because it's at
						///< the end of its life.  In this case we enter the
						///< closing state and try and close the connection
						///< gracefully.
} connection_reason_t;

typedef struct {
	fr_time_delta_t connection_timeout;	//!< How long to wait for the connection to open
						//!< or for shutdown to close the connection.
	fr_time_delta_t reconnection_delay;	//!< How long to wait after failures.
} connection_conf_t;

typedef struct connection_watch_entry_s connection_watch_entry_t;

extern fr_table_num_ordered_t const connection_states[];
extern size_t connection_states_len;

/** Callback for the initialise state
 *
 * Should attempt to open a non-blocking connection and return it in fd_out.
 *
 * @param[out] h_out	Where to write the new handle.
 * @param[in] conn	If integrating with a 3rd party library
 *			that will trigger connection API state transitions,
 *      		the connection should be passed as the uctx argument
 *			for library I/O callbacks.
 * @param[in] uctx	User context.
 * @return
 *	- #CONNECTION_STATE_CONNECTING	if a handle was successfully created.
 *	- #CONNECTION_STATE_FAILED		if we could not create a handle.
 */
typedef connection_state_t (*connection_init_t)(void **h_out, connection_t *conn, void *uctx);

/** Notification that the connection is now open
 *
 * This should be used to add any additional I/O events for the file descriptor
 * to call other code if it becomes readable or writable.
 *
 * @param[in] el	to use for inserting I/O events.
 * @param[in] h		Handle that was successfully opened.
 * @param[in] uctx	User context.
 * @return
 *	- #CONNECTION_STATE_CONNECTED	if the handle is usable.
 *	- #CONNECTION_STATE_FAILED		if the handle is unusable.
 */
typedef connection_state_t (*connection_open_t)(fr_event_list_t *el, void *h, void *uctx);

/** Start the process of gracefully shutting down the connection
 *
 * This function is called when the connection is signalled to gracefully
 * disconnect.  It should place the connection in a state where pending
 * I/O operations complete, and buffers are flushed.
 *
 * After all pending events are complete, the connection should be signalled
 * that the handle is in the closed state.
 *
 * @param[in] el	to use for inserting I/O events.
 * @param[in] h		Handle that needs to be closed.
 * @param[in] uctx	User context.
 * @return
 *	- #CONNECTION_STATE_SHUTDOWN		if the handle has shutdown.
 *	- #CONNECTION_STATE_FAILED		if the handle is unusable, and we
 *						should just transition directly to failed.
 */
typedef connection_state_t (*connection_shutdown_t)(fr_event_list_t *el, void *h, void *uctx);

/** Notification that a connection attempt has failed
 *
 * @note If the callback frees the connection, it must return #CONNECTION_STATE_HALTED.
 *
 * @param[in] h		Handle that failed.
 * @param[in] state	the connection was in when it failed. Usually one of:
 *			- #CONNECTION_STATE_CONNECTING	the connection attempt explicitly failed.
 *			- #CONNECTION_STATE_CONNECTED	something called #connection_signal_reconnect.
 *			- #CONNECTION_STATE_TIMEOUT		the connection attempt timed out.
 * @param[in] uctx	User context.
 * @return
 *	- #CONNECTION_STATE_INIT		to transition to the init state.
 *	- #CONNECTION_STATE_HALTED		To prevent further reconnection
 *						attempts Can be restarted with
 *	  					#connection_signal_init().
 */
typedef connection_state_t (*connection_failed_t)(void *h, connection_state_t state, void *uctx);

/** Notification that the connection has errored and must be closed
 *
 * This should be used to close the file descriptor.  It is assumed
 * that the file descriptor is invalid after this callback has been executed.
 *
 * If this callback does not close the file descriptor, the server will leak
 * file descriptors.
 *
 * @param[in] el	to use for inserting I/O events.
 * @param[in] h		Handle to close.
 * @param[in] uctx	User context.
 */
typedef void (*connection_close_t)(fr_event_list_t *el, void *h, void *uctx);

/** Holds a complete set of functions for a connection
 *
 */
typedef struct {
	connection_init_t		init;
	connection_open_t		open;
	connection_shutdown_t		shutdown;
	connection_failed_t		failed;
	connection_close_t		close;
} connection_funcs_t;

/** Receive a notification when a connection enters a particular state
 *
 * It is permitted for watchers to signal state changes, and/or to free the
 * connection.  The actual free will be deferred until the watcher returns.
 *
 * @param[in] conn	Being watched.
 * @param[in] prev	State we came from.
 * @param[in] state	State that was entered (the current state)
 * @param[in] uctx	that was passed to connection_add_watch_*.
 */
typedef void(*connection_watch_t)(connection_t *conn,
				  connection_state_t prev, connection_state_t state, void *uctx);

/** @name Add watcher functions that get called before (pre) the state callback and after (post)
 * @{
 */
connection_watch_entry_t *connection_add_watch_pre(connection_t *conn, connection_state_t state,
							 connection_watch_t watch, bool oneshot, void const *uctx);

connection_watch_entry_t *connection_add_watch_post(connection_t *conn, connection_state_t state,
							  connection_watch_t watch, bool oneshot, void const *uctx);

int			connection_del_watch_pre(connection_t *conn, connection_state_t state,
						    connection_watch_t watch);

int			connection_del_watch_post(connection_t *conn, connection_state_t state,
						     connection_watch_t watch);

void			connection_watch_enable(connection_watch_entry_t *entry);

void			connection_watch_disable(connection_watch_entry_t *entry);

void			connection_watch_enable_set_uctx(connection_watch_entry_t *entry, void const *uctx);

void			connection_watch_set_uctx(connection_watch_entry_t *entry, void const *uctx);

bool			connection_watch_is_enabled(connection_watch_entry_t *entry);
/** @} */

/** @name Statistics
 * @{
 */
uint64_t		connection_get_num_reconnected(connection_t const *conn);

uint64_t		connection_get_num_timed_out(connection_t const *conn);
/** @} */

/** @name Signal the connection to change states
 * @{
 */
void			connection_signal_init(connection_t *conn);

void			connection_signal_connected(connection_t *conn);

void			connection_signal_reconnect(connection_t *conn, connection_reason_t reason);

void			connection_signal_shutdown(connection_t *conn);

void			connection_signal_halt(connection_t *conn);

void			connection_signals_pause(connection_t *conn);

void			connection_signals_resume(connection_t *conn);
/** @} */

/** @name Install generic I/O events on an FD to signal state changes
 * @{
 */
int			connection_signal_on_fd(connection_t *conn, int fd);
/** @} */

/** @name Allocate a new connection
 * @{
 */
connection_t		*connection_alloc(TALLOC_CTX *ctx, fr_event_list_t *el,
					     connection_funcs_t const *funcs, connection_conf_t const *conf,
					     char const *log_prefix, void const *uctx);
/** @} */

#undef _CONST

#ifdef __cplusplus
}
#endif
