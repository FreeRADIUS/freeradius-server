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
 * @file lib/server/connection.h
 * @brief Simple state machine for managing connection states.
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include <talloc.h>
#include <freeradius-devel/util/event.h>
#include <freeradius-devel/util/token.h>

typedef struct fr_conn fr_connection_t;

typedef enum {
	FR_CONNECTION_STATE_HALTED = 0,		//!< The connection is in a halted stat.  It does not have
						///< a valid file descriptor, and it will not try and
						///< and create one.
	FR_CONNECTION_STATE_INIT,		//!< Init state, sets up connection.
	FR_CONNECTION_STATE_CONNECTING,		//!< Waiting for connection to establish.
	FR_CONNECTION_STATE_TIMEOUT,		//!< Timeout during #FR_CONNECTION_STATE_CONNECTING.
	FR_CONNECTION_STATE_CONNECTED,		//!< File descriptor is open (ready for writing).
	FR_CONNECTION_STATE_FAILED		//!< Connection failed and is waiting to reconnect.
} fr_connection_state_t;

extern FR_NAME_NUMBER const fr_connection_states[];

/** Callback for the initialise state
 *
 * Should attempt to open a non-blocking connection and return it in fd_out.
 *
 * @param[out] fd_out	Where to write the new file descriptor.
 * @param[in] uctx	User context.
 * @return
 *	- #FR_CONNECTION_STATE_CONNECTING	if a file descriptor was successfully created.
 *	- #FR_CONNECTION_STATE_FAILED		if we could not open a file descriptor.
 */
typedef fr_connection_state_t (*fr_connection_init_t)(int *fd_out, void *uctx);

/** Notification that the connection is now open
 *
 * This should be used to add any additional I/O events for the file descriptor
 * to call other code if it becomes readable or writable.
 *
 * @param[in] el	to use for inserting I/O events.
 * @param[in] fd	That was successfully opened.
 * @param[in] uctx	User context.
 * @return
 *	- #FR_CONNECTION_STATE_CONNECTED	if the file descriptor is useable.
 *	- #FR_CONNECTION_STATE_FAILED		if the file descriptor is unusable.
 */
typedef fr_connection_state_t (*fr_connection_open_t)(fr_event_list_t *el, int fd, void *uctx);

/** Notification that a connection attempt has failed
 *
 * @note If the callback frees the connection, it must return #FR_CONNECTION_STATE_HALTED.
 *
 * @param[in] fd	That was successfully opened.
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
typedef fr_connection_state_t (*fr_connection_failed_t)(int fd, fr_connection_state_t state, void *uctx);

/** Notification that the connection has errored and must be closed
 *
 * This should be used to close the file descriptor.  It is assumed
 * that the file descriptor is invalid after this callback has been executed.
 *
 * If this callback does not close the file descriptor, the server will leak
 * file descriptors.
 *
 * @param[in] fd	to close.
 * @param[in] uctx	User context.
 */
typedef void (*fr_connection_close_t)(int fd, void *uctx);

fr_connection_t		*fr_connection_alloc(TALLOC_CTX *ctx, fr_event_list_t *el,
					     struct timeval const *connection_timeout,
					     struct timeval const *reconnection_delay,
					     fr_connection_init_t init, fr_connection_open_t open,
					     fr_connection_close_t close,
					     char const *log_prefix, void *uctx);

void			fr_connection_failed_func(fr_connection_t *conn, fr_connection_failed_t func);
void			fr_connection_signal_init(fr_connection_t *conn);
void			fr_connection_signal_open(fr_connection_t *conn);
void			fr_connection_signal_reconnect(fr_connection_t *conn);

fr_event_list_t		*fr_connection_get_el(fr_connection_t const *conn);
int			fr_connection_get_fd(fr_connection_t const *conn);
void			fr_connection_set_fd(fr_connection_t *conn, int fd);


