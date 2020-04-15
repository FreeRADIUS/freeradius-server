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

#include <talloc.h>

#ifndef _CONNECTION_PRIVATE
typedef struct fr_connection_pub_s fr_connection_t; /* We use the private version of the fr_connection_t */
#  define _CONST const
#else
#  define _CONST
#endif

typedef enum {
	FR_CONNECTION_STATE_HALTED = 0,		//!< The connection is in a halted stat.  It does not have
						///< a valid file descriptor, and it will not try and
						///< and create one.
	FR_CONNECTION_STATE_INIT,		//!< Init state, sets up connection.
	FR_CONNECTION_STATE_CONNECTING,		//!< Waiting for connection to establish.
	FR_CONNECTION_STATE_TIMEOUT,		//!< Timeout during #FR_CONNECTION_STATE_CONNECTING.
	FR_CONNECTION_STATE_CONNECTED,		//!< File descriptor is open (ready for writing).
	FR_CONNECTION_STATE_SHUTDOWN,		//!< Connection is shutting down.
	FR_CONNECTION_STATE_FAILED,		//!< Connection has failed.
	FR_CONNECTION_STATE_CLOSED,		//!< Connection has been closed.
	FR_CONNECTION_STATE_MAX
} fr_connection_state_t;

/** Public fields for the connection
 *
 * This saves the overhead of using accessors for commonly used fields in
 * connections.
 *
 * Though these fields are public, they should _NOT_ be modified by clients of
 * the connection API.
 */
struct fr_connection_pub_s {
	fr_connection_state_t _CONST	state;		//!< Current connection state.
	uint64_t _CONST			id;		//!< Unique identifier for the connection.
	void			* _CONST h;		//!< Connection handle
	fr_event_list_t		* _CONST el;		//!< Event list for timers and I/O events.
	char const		* _CONST log_prefix;	//!< Prefix to add to log messages.

	uint64_t _CONST			reconnected;	//!< How many times we've attempted to establish or
							///< re-establish this connection.
	uint64_t _CONST			timed_out;	//!< How many times has this connection timed out when
							///< connecting.
	bool _CONST			triggers;	//!< do we run the triggers?
};

typedef enum {
	FR_CONNECTION_FAILED = 0,		//!< Connection is being reconnected because it failed.
	FR_CONNECTION_EXPIRED 			//!< Connection is being reconnected because it's at
						///< the end of its life.  In this case we enter the
						///< closing state and try and close the connection
						///< gracefully.
} fr_connection_reason_t;

typedef struct {
	fr_time_delta_t connection_timeout;	//!< How long to wait for the connection to open
						//!< or for shutdown to close the connection.
	fr_time_delta_t reconnection_delay;	//!< How long to wait after failures.
} fr_connection_conf_t;

typedef struct fr_connection_watch_entry_s fr_connection_watch_entry_t;

extern fr_table_num_ordered_t const fr_connection_states[];
extern size_t fr_connection_states_len;

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
 *	- #FR_CONNECTION_STATE_CONNECTING	if a handle was successfully created.
 *	- #FR_CONNECTION_STATE_FAILED		if we could not create a handle.
 */
typedef fr_connection_state_t (*fr_connection_init_t)(void **h_out, fr_connection_t *conn, void *uctx);

/** Notification that the connection is now open
 *
 * This should be used to add any additional I/O events for the file descriptor
 * to call other code if it becomes readable or writable.
 *
 * @param[in] el	to use for inserting I/O events.
 * @param[in] h		Handle that was successfully opened.
 * @param[in] uctx	User context.
 * @return
 *	- #FR_CONNECTION_STATE_CONNECTED	if the handle is useable.
 *	- #FR_CONNECTION_STATE_FAILED		if the handle is unusable.
 */
typedef fr_connection_state_t (*fr_connection_open_t)(fr_event_list_t *el, void *h, void *uctx);

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
 *	- #FR_CONNECTION_STATE_SHUTDOWN		if the handle has shutdown.
 *	- #FR_CONNECTION_STATE_FAILED		if the handle is unusable, and we
 *						should just transition directly to failed.
 */
typedef fr_connection_state_t (*fr_connection_shutdown_t)(fr_event_list_t *el, void *h, void *uctx);

/** Notification that a connection attempt has failed
 *
 * @note If the callback frees the connection, it must return #FR_CONNECTION_STATE_HALTED.
 *
 * @param[in] h		Handle that failed.
 * @param[in] state	the connection was in when it failed. Usually one of:
 *			- #FR_CONNECTION_STATE_CONNECTING	the connection attempt explicitly failed.
 *			- #FR_CONNECTION_STATE_CONNECTED	something called #fr_connection_signal_reconnect.
 *			- #FR_CONNECTION_STATE_TIMEOUT		the connection attempt timed out.
 * @param[in] uctx	User context.
 * @return
 *	- #FR_CONNECTION_STATE_INIT		to transition to the init state.
 *	- #FR_CONNECTION_STATE_HALTED		To prevent further reconnection
 *						attempts Can be restarted with
 *	  					#fr_connection_signal_init().
 */
typedef fr_connection_state_t (*fr_connection_failed_t)(void *h, fr_connection_state_t state, void *uctx);

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
typedef void (*fr_connection_close_t)(fr_event_list_t *el, void *h, void *uctx);

/** Holds a complete set of functions for a connection
 *
 */
typedef struct {
	fr_connection_init_t		init;
	fr_connection_open_t		open;
	fr_connection_shutdown_t	shutdown;
	fr_connection_failed_t		failed;
	fr_connection_close_t		close;
} fr_connection_funcs_t;

/** Receive a notification when a connection enters a particular state
 *
 * It is permitted for watchers to signal state changes, and/or to free the
 * connection.  The actual free will be deferred until the watcher returns.
 *
 * @param[in] conn	Being watched.
 * @param[in] state	That was entered.
 * @param[in] uctx	that was passed to fr_connection_add_watch_*.
 */
typedef void(*fr_connection_watch_t)(fr_connection_t *conn, fr_connection_state_t state, void *uctx);

/** @name Add watcher functions that get called before (pre) the state callback and after (post)
 * @{
 */
fr_connection_watch_entry_t *fr_connection_add_watch_pre(fr_connection_t *conn, fr_connection_state_t state,
							 fr_connection_watch_t watch, bool oneshot, void const *uctx);

fr_connection_watch_entry_t *fr_connection_add_watch_post(fr_connection_t *conn, fr_connection_state_t state,
							  fr_connection_watch_t watch, bool oneshot, void const *uctx);

int			fr_connection_del_watch_pre(fr_connection_t *conn, fr_connection_state_t state,
						    fr_connection_watch_t watch);

int			fr_connection_del_watch_post(fr_connection_t *conn, fr_connection_state_t state,
						     fr_connection_watch_t watch);

void			fr_connection_watch_enable(fr_connection_watch_entry_t *entry);

void			fr_connection_watch_disable(fr_connection_watch_entry_t *entry);

void			fr_connection_watch_enable_set_uctx(fr_connection_watch_entry_t *entry, void const *uctx);

void			fr_connection_watch_set_uctx(fr_connection_watch_entry_t *entry, void const *uctx);

bool			fr_connection_watch_is_enabled(fr_connection_watch_entry_t *entry);
/** @} */

/** @name Statistics
 * @{
 */
uint64_t		fr_connection_get_num_reconnected(fr_connection_t const *conn);

uint64_t		fr_connection_get_num_timed_out(fr_connection_t const *conn);
/** @} */

/** @name Signal the connection to change states
 * @{
 */
void			fr_connection_signal_init(fr_connection_t *conn);

void			fr_connection_signal_connected(fr_connection_t *conn);

void			fr_connection_signal_reconnect(fr_connection_t *conn, fr_connection_reason_t reason);

void			fr_connection_signal_shutdown(fr_connection_t *conn);

void			fr_connection_signal_halt(fr_connection_t *conn);

void			fr_connection_signals_pause(fr_connection_t *conn);

void			fr_connection_signals_resume(fr_connection_t *conn);
/** @} */

/** @name Install generic I/O events on an FD to signal state changes
 * @{
 */
int			fr_connection_signal_on_fd(fr_connection_t *conn, int fd);
/** @} */

/** @name Allocate a new connection
 * @{
 */
fr_connection_t		*fr_connection_alloc(TALLOC_CTX *ctx, fr_event_list_t *el,
					     fr_connection_funcs_t const *funcs, fr_connection_conf_t const *conf,
					     char const *log_prefix, void const *uctx);
/** @} */

#undef _CONST

#ifdef __cplusplus
}
#endif


